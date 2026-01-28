import httpx
from .config import settings

import logging
logger = logging.getLogger(__name__)

class PowerDNSClient:
    """Client for interacting with the PowerDNS API."""
    def __init__(self, api_url: str, api_key: str, server_id: str):
        self.base_url = api_url
        self.headers = {"X-API-Key": api_key}
        self.server_id = server_id
        self.timeout = httpx.Timeout(settings.PDNS_TIMEOUT)
        self.limits = httpx.Limits(
            max_connections=settings.PDNS_MAX_CONNECTIONS, 
            max_keepalive_connections=settings.PDNS_MAX_KEEPALIVE
        )
        logger.info("PowerDNSClient initialized with base_url=%s, server_id=%s", self.base_url, self.server_id)

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
