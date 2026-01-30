import httpx
from typing import Self, Optional
from fastapi import HTTPException

from .config import settings
from .database import dbmgr

import logging
logger = logging.getLogger(__name__)

class PowerDNSClient:
    """Client for interacting with the PowerDNS API."""
    
    _registry: list[Self] = [] # Stores initialized client instances

    @classmethod
    async def initialize_all_clients(cls):
        cls._registry.clear()
        for cli in await dbmgr.get_all_pdns_servers():
            await cls.get_or_create_by_pk(cli.tid)

    @classmethod
    def get(cls, tid: int) -> Optional[Self]:
        if tid == -1:
            if len(cls._registry) > 0:
                return cls._registry[0]
            return None
        for i in cls._registry:
            if tid == i.tid:
                return i
        return None

    @classmethod
    async def _initialize_and_register_client(cls, pdns_server_obj) -> Self:
        # Check if already in registry (e.g., fetched by server_id, then by pk)
        existing_client = cls.get(pdns_server_obj.tid)
        if existing_client:
            return existing_client

        # Perform initial API call to fetch server details if missing
        if not pdns_server_obj.version or pdns_server_obj.version is None:
            logger.info("Fetching initial server details for server_id=%s (tid=%s)", pdns_server_obj.server_id, pdns_server_obj.tid)
            async with httpx.AsyncClient(timeout=settings.PDNS_TIMEOUT, limits=httpx.Limits(max_connections=settings.PDNS_MAX_CONNECTIONS, max_keepalive_connections=settings.PDNS_MAX_KEEPALIVE)) as client:
                try:
                    response = await client.get(
                        f"{pdns_server_obj.api_url}/servers/{pdns_server_obj.server_id}",
                        headers={"X-API-Key": pdns_server_obj.api_key}
                    )
                    response.raise_for_status()
                    payload = response.json()
                    pdns_server_obj.version = payload.get('version')
                    pdns_server_obj.daemon_type = payload.get('daemon_type')
                    pdns_server_obj.config_url = payload.get('config_url')
                    pdns_server_obj.zones_url = payload.get('zones_url')
                    await dbmgr.update_pdns_server_details(
                        pdns_server_obj.tid,
                        pdns_server_obj.version,
                        pdns_server_obj.daemon_type,
                        pdns_server_obj.config_url,
                        pdns_server_obj.zones_url
                    )
                    logger.info("Successfully fetched and updated server details for server_id=%s", pdns_server_obj.server_id)
                except httpx.HTTPError as e:
                    logger.error("Failed to fetch initial server details for server_id=%s: %s", pdns_server_obj.server_id, e, exc_info=True)
                    # raise HTTPException(status_code=500, detail=f"Failed to connect to PowerDNS API for server {pdns_server_obj.server_id}: {e}")

        instance = cls(pdns_server_obj)
        cls._registry.append(instance)
        logger.info("PowerDNSClient instance for server_id=%s (tid=%s) added to registry.", instance.server_id, instance.tid)
        return instance

    @classmethod
    async def get_or_create_by_pk(cls, tid: int) -> Self:
        """Retrieves an existing client by primary key (tid) or creates a new one."""
        if tid == -1:
            if len(cls._registry) > 0:
                return cls._registry[0]
            return None
        client = cls.get(tid)
        if client:
            return client
        
        pdns_server_obj = await dbmgr.get_pdns_server_by_pk(tid)
        if not pdns_server_obj:
            logger.error("PowerDNS server details not found for tid '%s'.", tid)
            raise HTTPException(status_code=500, detail="PowerDNS server configuration missing.")
        
        return await cls._initialize_and_register_client(pdns_server_obj)

    @classmethod
    async def ping_all(cls):
        for i in cls._registry:
            await i.ping()

    @classmethod
    async def getClients(cls) -> list[Self]:
        await cls.ping_all()
        return cls._registry
    
    def __init__(self, pdns_server_obj):
        """Initializes a PowerDNSClient instance from a PDNSServer database object."""
        self.tid = pdns_server_obj.tid
        self.base_url = pdns_server_obj.api_url
        self.headers = {"X-API-Key": pdns_server_obj.api_key}
        self.server_id = pdns_server_obj.server_id
        self.nickname = pdns_server_obj.nickname
        self.version = pdns_server_obj.version
        self.daemon_type = pdns_server_obj.daemon_type
        self.config_url = pdns_server_obj.config_url
        self.zones_url = pdns_server_obj.zones_url
        
        self.timeout = httpx.Timeout(settings.PDNS_TIMEOUT)
        self.limits = httpx.Limits(
            max_connections=settings.PDNS_MAX_CONNECTIONS, 
            max_keepalive_connections=settings.PDNS_MAX_KEEPALIVE
        )
        self.status = False
        logger.debug("PowerDNSClient instance created for server_id=%s (tid=%s)", self.server_id, self.tid)


    async def ping(self):
        """Ping Server API. Should return 200 OK.

        Returns:
            bool: True if ping was successful.
        """
        logger.debug("Attempting to ping PowerDNS API profile %s", self.nickname)
        self.status = False
        try:
            async with httpx.AsyncClient(timeout=self.timeout, limits=self.limits) as client:
                response = await client.get(
                    f"{self.base_url}/servers/{self.server_id}",
                    headers=self.headers
                )
                if response.status_code == 200:
                    logger.info("Successfully pinged PowerDNS API profile %s", self.nickname)
                    self.status = True
                    return True 
                else:
                    logger.warning("Ping failed for PowerDNS API profile %s with HTTP status %u",self.nickname, response.status_code)
                    return False
        except (httpx.ConnectError, httpx.HTTPError) as e:
            logger.error("Ping failed for PowerDNS API profile %s: %s", self.nickname)
        return False    
 
    async def get_zones(self):
        """Retrieves the list of all zones.

        Returns:
            list: A list of dictionaries representing the zones.
        """
        logger.debug("Attempting to retrieve all zones from PowerDNS API.")
        async with httpx.AsyncClient(timeout=self.timeout, limits=self.limits) as client:
            response = await client.get(
                f"{self.base_url}/servers/{self.server_id}/zones",
                headers=self.headers
            )
            response.raise_for_status()
            logger.info("Successfully retrieved %d zones.", len(response.json()))
            return response.json()

    async def get_zone(self, zone_id: str):
        logger.debug("Attempting to retrieve zone details for zone_id=%s", zone_id)

        """Retrieves details of a zone (including records).

        Args:
            zone_id (str): The canonical name of the zone.

        Returns:
            dict: A dictionary containing zone details and RRsets.
        """
        async with httpx.AsyncClient(timeout=self.timeout, limits=self.limits) as client:
            response = await client.get(
                f"{self.base_url}/servers/{self.server_id}/zones/{zone_id}",
                headers=self.headers
            )
            response.raise_for_status()
            logger.info("Successfully retrieved details for zone_id=%s", zone_id)
            return response.json()

    async def create_zone(self, domain: str, kind: str = "Native", nameservers: list = None):
        """Creates a new DNS zone.

        Args:
            domain (str): The domain name of the zone.
            kind (str, optional): The type of zone (Native, Master, Slave). Defaults to "Native".
            nameservers (list, optional): List of nameservers. Defaults to None.

        Returns:
            dict: The created zone details.
        """
        logger.info("Attempting to create zone: domain=%s, kind=%s", domain, kind)
        if nameservers is None:
            nameservers = [f"ns1.{domain}", f"ns2.{domain}"]
            
        payload = {
            "name": domain if domain.endswith('.') else f"{domain}.",
            "kind": kind,
            "masters": [],
            "nameservers": nameservers
        }
        
        async with httpx.AsyncClient(timeout=self.timeout, limits=self.limits) as client:
            response = await client.post(
                f"{self.base_url}/servers/{self.server_id}/zones",
                headers=self.headers,
                json=payload
            )
            logger.info("Zone creation response status: %d", response.status_code)
            response.raise_for_status()
            return response.json()

    async def delete_zone(self, zone_id: str):
        """Deletes a zone.

        Args:
            zone_id (str): The canonical name of the zone to delete.

        Returns:
            bool: True if deletion was successful.
        """
        logger.info("Attempting to delete zone: zone_id=%s", zone_id)
        async with httpx.AsyncClient(timeout=self.timeout, limits=self.limits) as client:
            response = await client.delete(
                f"{self.base_url}/servers/{self.server_id}/zones/{zone_id}",
                headers=self.headers
            )
            if response.status_code != 204:
                logger.error("Zone deletion failed for zone_id=%s with status %d: %s", zone_id, response.status_code, response.text)
                response.raise_for_status()
            logger.info("Successfully deleted zone: zone_id=%s", zone_id)
            return True

    async def manage_record(self, zone_id: str, name: str, rtype: str, content: list, ttl: int = 3600, changetype: str = "REPLACE"):
        """Adds, modifies or deletes records (RRsets).

        To delete a record, pass an empty list for content and changetype="DELETE".

        Args:
            zone_id (str): The canonical name of the zone.
            name (str): The name of the record (FQDN).
            rtype (str): The DNS record type (A, MX, etc.).
            content (list): List of content strings for the record.
            ttl (int, optional): Time To Live. Defaults to 3600.
            changetype (str, optional): Operation type (REPLACE or DELETE). Defaults to "REPLACE".
        """
        logger.info("Managing record in zone %s: name=%s, type=%s, changetype=%s", zone_id, name, rtype, changetype)
        records = [{"content": c, "disabled": False} for c in content]
        
        payload = {
            "rrsets": [
                {
                    "name": name,
                    "type": rtype,
                    "ttl": ttl,
                    "changetype": changetype,
                    "records": records
                }
            ]
        }
        
        async with httpx.AsyncClient(timeout=self.timeout, limits=self.limits) as client:
            response = await client.patch(
                f"{self.base_url}/servers/{self.server_id}/zones/{zone_id}",
                headers=self.headers,
                json=payload
            )
            logger.info("Record management response status: %d", response.status_code)
            response.raise_for_status()

    async def batch_apply_records(self, zone_id: str, rrsets: list):
        """Applies multiple record modifications in a single request.

        Args:
            zone_id (str): The canonical name of the zone.
            rrsets (list): A list of RRset dictionaries to apply.
        """
        logger.info("Batch applying %d record changes to zone %s", len(rrsets), zone_id)
        payload = {"rrsets": rrsets}
        async with httpx.AsyncClient(timeout=self.timeout, limits=self.limits) as client:
            response = await client.patch(
                f"{self.base_url}/servers/{self.server_id}/zones/{zone_id}",
                headers=self.headers,
                json=payload
            )
            logger.info("Batch apply response status: %d", response.status_code)
            response.raise_for_status()
