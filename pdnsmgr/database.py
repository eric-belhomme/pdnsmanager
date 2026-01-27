from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, select, delete, update
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets
import logging
import string
import os
from .utils import check_policy_match
from .config import settings

logger = logging.getLogger(__name__)

Base = declarative_base()
ph = PasswordHasher()

class RBACGroup(Base):
    __tablename__ = "rbac_groups"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    type = Column(String, default="local")

class RBACUser(Base):
    __tablename__ = "rbac_users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    name = Column(String)
    email = Column(String)
    type = Column(String, default="local")
    password_hash = Column(String, nullable=True)

class RBACGroupMember(Base):
    __tablename__ = "rbac_group_members"
    id = Column(Integer, primary_key=True)
    group_name = Column(String, index=True)
    username = Column(String, index=True)

class RBACPolicy(Base):
    __tablename__ = "rbac_policies"
    id = Column(Integer, primary_key=True)
    zone_name = Column(String, index=True)
    entity_name = Column(String, index=True) # username or group name
    role = Column(String) # owner, write, read, none

class DBManager:
    def __init__(self):
        self.engine = create_async_engine(settings.DATABASE_URL, echo=False)
        self.async_session = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    def verify_password(self, plain_password, hashed_password):
        if not hashed_password:
            return False
        try:
            result = ph.verify(hashed_password, plain_password)
            logger.debug("Password verification successful.")
            return result
        except VerifyMismatchError:
            logger.warning("Password verification failed: Mismatch error.")
            return False
        except Exception as e:
            logger.error("An unexpected error occurred during password verification: %s", e, exc_info=True)
            return False

    def get_password_hash(self, password): # type: ignore
        return ph.hash(password)

    async def init_db(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        async with self.async_session() as session:
            # Check if admin user exists
            stmt = select(RBACUser).where(RBACUser.username == "admin")
            result = await session.execute(stmt)
            logger.debug("Checking for existing 'admin' user.")
            if not result.scalars().first():
                # Generate robust password
                alphabet = string.ascii_letters + string.digits + string.punctuation
                password = ''.join(secrets.choice(alphabet) for _ in range(32))
                hashed = self.get_password_hash(password)
                
                # Create default admin user
                logger.info("Creating default 'admin' user.")
                session.add(RBACUser(username="admin", name="Administrator", type="local", password_hash=hashed))
                
                # Write password to file
                with open("admin_password", "w") as f:
                    f.write(password)
                logger.warning("Default admin password written to 'admin_password' file. PLEASE CHANGE IT!")
                try:
                    os.chmod("admin_password", 0o400)
                    logger.debug("Set permissions for 'admin_password' file to 0o400.")
                except OSError as e:
                    logger.warning("Could not set permissions for 'admin_password' file: %s", e)
                
                # Ensure admin group and policy
                logger.debug("Ensuring 'admins' group and policy exist.")
                if not (await session.execute(select(RBACGroup).where(RBACGroup.name == "admins"))).scalars().first():
                    session.add(RBACGroup(name="admins", type="local"))
                    logger.info("Created 'admins' group.")
                    session.add(RBACGroupMember(group_name="admins", username="admin"))
                    session.add(RBACPolicy(zone_name="*", entity_name="admins", role="owner"))
                
                await session.commit()

    async def get_user_groups(self, username, extra_groups=None):
        user_groups = list(extra_groups) if extra_groups else []
        
        logger.debug("Retrieving local groups for user '%s'.", username)
        async with self.async_session() as session:
            result = await session.execute(
                select(RBACGroupMember.group_name).where(RBACGroupMember.username == username)
            )
            user_groups.extend(result.scalars().all())
            
        logger.debug("User '%s' is a member of groups: %s", username, list(set(user_groups)))
        return list(set(user_groups))

    async def get_role(self, user, zone_name):
        username = user.get('username', user.get('name'))
        oidc_groups = user.get('groups', [])

        # Normalize zone name (ensure trailing dot)
        if zone_name and not zone_name.endswith('.'):
            zone_name += '.'
        
        logger.debug("Determining role for user '%s' on zone '%s'. OIDC groups: %s", username, zone_name, oidc_groups)
        # Get all groups for the user
        groups = await self.get_user_groups(username, oidc_groups)
        entities = [username] + groups

        async with self.async_session() as session:
            # Fetch all policies that could potentially apply to this zone and user/groups
            # This includes exact zone matches, wildcard '*', and '*.suffix' matches.
            
            # First, get all policies for the relevant entities
            stmt = select(RBACPolicy).where(
                RBACPolicy.entity_name.in_(entities)
            )
            all_potential_policies = (await session.execute(stmt)).scalars().all()
            
            # Now, filter these policies based on zone matching logic
            applicable_policies = []
            for policy in all_potential_policies:
                if check_policy_match(policy.zone_name, zone_name):
                    applicable_policies.append(policy)
            
            logger.debug("Found %d applicable policies for user/groups on zone '%s'. Policies: %s", len(applicable_policies), zone_name, [f"{p.zone_name}:{p.entity_name}:{p.role}" for p in applicable_policies])
            policies = applicable_policies
        
        # Check user specific role
        for p in policies:
            if p.entity_name == username:
                logger.info("User '%s' has explicit role '%s' for zone '%s' via policy '%s'.", username, p.role, zone_name, p.zone_name)
                return p.role
        
        # Check group roles
        roles_priority = {'owner': 4, 'write': 3, 'read': 2, 'none': 1}
        max_priority = 0
        effective_role = 'none'

        for p in policies:
            # We know p.entity_name is in 'groups' because of the query filter and the check above
            if p.entity_name in groups: # Only consider group policies here, as user policies were handled above
                role = p.role
            priority = roles_priority.get(role, 0)
            if priority > max_priority:
                max_priority = priority
                effective_role = role
        
        logger.info("Effective role for user '%s' on zone '%s' is '%s'.", username, zone_name, effective_role)
        return effective_role

    def can_write_record(self, role, record_type):
        if role == 'owner': return True
        if role == 'write': return record_type not in ['SOA', 'NS']
        logger.debug("Permission check: role='%s', record_type='%s' -> False", role, record_type)
        return False

    async def get_all_groups(self):
        async with self.async_session() as session:
            result = await session.execute(select(RBACGroup).order_by(RBACGroup.name))
            return result.scalars().all()

    async def create_group(self, name, type="local"):
        async with self.async_session() as session:
            logger.info("Attempting to create group '%s' (type: %s).", name, type)
            try:
                session.add(RBACGroup(name=name, type=type))
                await session.commit()
                logger.info("Group '%s' created successfully.", name)
            except Exception as e:
                await session.rollback()
                logger.error("Failed to create group '%s': %s", name, e, exc_info=True)

    async def rename_group(self, group_id, new_name):
        async with self.async_session() as session:
            group = await session.get(RBACGroup, group_id)
            if group:
                if group.type == "oidc":
                    raise ValueError("Cannot rename OIDC group")
                logger.info("Attempting to rename group ID %d from '%s' to '%s'.", group_id, group.name, new_name)
                old_name = group.name
                
                group.name = new_name
                # Update references in members and policies
                await session.execute(
                    update(RBACGroupMember)
                    .where(RBACGroupMember.group_name == old_name)
                    .values(group_name=new_name)
                )
                await session.execute(
                    update(RBACPolicy)
                    .where(RBACPolicy.entity_name == old_name)
                    .values(entity_name=new_name)
                )
                await session.commit() # type: ignore
                logger.info("Group ID %d renamed to '%s' successfully.", group_id, new_name)
            else:
                logger.warning("Attempted to rename non-existent group ID %d.", group_id)

    async def delete_group(self, group_id):
        async with self.async_session() as session:
            group = await session.get(RBACGroup, group_id)
            if group:
                logger.info("Attempting to delete group ID %d ('%s').", group_id, group.name)
                await session.execute(delete(RBACGroupMember).where(RBACGroupMember.group_name == group.name))
                await session.delete(group)
                await session.commit()

    async def get_all_members(self):
        async with self.async_session() as session:
            result = await session.execute(select(RBACGroupMember).order_by(RBACGroupMember.group_name, RBACGroupMember.username))
            return result.scalars().all()

    async def add_member(self, group_name, username):
        async with self.async_session() as session:
            stmt = select(RBACGroupMember).where(RBACGroupMember.group_name == group_name, RBACGroupMember.username == username)
            logger.info("Attempting to add user '%s' to group '%s'.", username, group_name)
            if not (await session.execute(stmt)).scalars().first():
                session.add(RBACGroupMember(group_name=group_name, username=username))
                await session.commit()
                logger.info("User '%s' added to group '%s' successfully.", username, group_name)
            else:
                logger.debug("User '%s' is already a member of group '%s'.", username, group_name)
    async def delete_member(self, member_id):
        async with self.async_session() as session:
            member = await session.get(RBACGroupMember, member_id)
            if member:
                await session.delete(member)
                await session.commit()

    async def remove_member(self, group_name, username):
        async with self.async_session() as session:
            stmt = select(RBACGroupMember).where(RBACGroupMember.group_name == group_name, RBACGroupMember.username == username)
            logger.info("Attempting to remove user '%s' from group '%s'.", username, group_name)
            member = (await session.execute(stmt)).scalars().first()
            if member:
                await session.delete(member)
                await session.commit()
                logger.info("User '%s' removed from group '%s' successfully.", username, group_name)
            else:
                logger.warning("Attempted to remove non-existent member: user '%s' from group '%s'.", username, group_name)

    async def get_all_policies(self):
        async with self.async_session() as session:
            result = await session.execute(select(RBACPolicy).order_by(RBACPolicy.zone_name))
            return result.scalars().all()

    async def create_policy(self, zone_name, entity_name, role):
        async with self.async_session() as session:
            logger.info("Attempting to create policy: zone='%s', entity='%s', role='%s'.", zone_name, entity_name, role)
            session.add(RBACPolicy(zone_name=zone_name, entity_name=entity_name, role=role))
            await session.commit()
            logger.info("Policy created successfully.")


    async def update_policy(self, policy_id, zone_name, entity_name, role):
        async with self.async_session() as session:
            policy = await session.get(RBACPolicy, policy_id)
            if policy:
                policy.zone_name = zone_name
                policy.entity_name = entity_name
                policy.role = role
                await session.commit() # type: ignore
                logger.info("Policy ID %d updated successfully.", policy_id)
            else:
                logger.warning("Attempted to update non-existent policy ID %d.", policy_id)

    async def delete_policy(self, policy_id):
        async with self.async_session() as session:
            policy = await session.get(RBACPolicy, policy_id)
            if policy:
                await session.delete(policy)
                logger.info("Policy ID %d deleted successfully.", policy_id)
                await session.commit()

    async def get_all_users(self):
        async with self.async_session() as session:
            result = await session.execute(select(RBACUser).order_by(RBACUser.username))
            return result.scalars().all()

    async def get_user(self, username):
        async with self.async_session() as session:
            result = await session.execute(select(RBACUser).where(RBACUser.username == username))
            logger.debug("Retrieving user '%s'.", username)
            return result.scalars().first()

    async def create_user(self, username, name=None, email=None, type="local", password=None):
        if not name: name = username
        hashed = self.get_password_hash(password) if password else None
        async with self.async_session() as session:
            logger.info("Attempting to create user '%s' (type: %s).", username, type)
            try:
                session.add(RBACUser(username=username, name=name, email=email, type=type, password_hash=hashed))
                await session.commit()
                logger.info("User '%s' created successfully.", username)
            except Exception as e:
                await session.rollback()
                logger.error("Failed to create user '%s': %s", username, e, exc_info=True)

    async def update_user(self, username, name=None, email=None, password=None):
        async with self.async_session() as session:
            logger.info("Attempting to update user '%s'.", username)
            stmt = select(RBACUser).where(RBACUser.username == username)
            user = (await session.execute(stmt)).scalars().first()
            if user:
                if name is not None: user.name = name or username
                if email is not None: user.email = email
                if password: user.password_hash = self.get_password_hash(password)
                await session.commit()
                logger.info("User '%s' updated successfully.", username)
            else:
                logger.warning("Attempted to update non-existent user '%s'.", username)

    async def delete_user(self, username):
        async with self.async_session() as session:
            stmt = select(RBACUser).where(RBACUser.username == username)
            user = (await session.execute(stmt)).scalars().first()
            if user:
                logger.info("Attempting to delete user '%s'.", username)
                await session.delete(user)
                await session.execute(delete(RBACGroupMember).where(RBACGroupMember.username == username))
                await session.execute(delete(RBACPolicy).where(RBACPolicy.entity_name == username))
                await session.commit()
                logger.info("User '%s' and associated data deleted successfully.", username)

    async def sync_oidc_user(self, username, name, email, groups):
        async with self.async_session() as session:
            # Sync User
            stmt = select(RBACUser).where(RBACUser.username == username)
            user = (await session.execute(stmt)).scalars().first()
            if not user:
                logger.info("Creating new OIDC user '%s'.", username)
                user = RBACUser(username=username, name=name or username, email=email, type="oidc")
                session.add(user)
            else:
                # Update OIDC user info
                if user.type != "oidc":
                    logger.warning("Existing local user '%s' is being converted to OIDC type.", username)
                user.name = name or username
                user.email = email
                user.type = "oidc"
            
            for group_name in groups:
                # Ensure group exists
                stmt = select(RBACGroup).where(RBACGroup.name == group_name)
                result = await session.execute(stmt)
                group = result.scalars().first()
                if not group:
                    logger.info("Creating new OIDC group '%s'.", group_name)
                    group = RBACGroup(name=group_name, type="oidc")
                    session.add(group)
                    await session.flush()
                
                # Ensure membership
                stmt_member = select(RBACGroupMember).where(RBACGroupMember.group_name == group_name, RBACGroupMember.username == username)
                logger.debug("Ensuring user '%s' is member of group '%s'.", username, group_name)
                if not (await session.execute(stmt_member)).scalars().first():
                    session.add(RBACGroupMember(group_name=group_name, username=username))
                    logger.info("User '%s' added to OIDC group '%s'.", username, group_name)
            await session.commit()
            logger.info("OIDC user '%s' and groups synced successfully.", username)

dbmgr = DBManager()
