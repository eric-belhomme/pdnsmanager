import httpx
from config import settings

class PowerDNSClient:
    def __init__(self):
        self.base_url = settings.PDNS_API_URL
        self.headers = {"X-API-Key": settings.PDNS_API_KEY}
        self.server_id = settings.PDNS_SERVER_ID

    async def get_zones(self):
        """Récupère la liste de toutes les zones."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/servers/{self.server_id}/zones",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()

    async def get_zone(self, zone_id: str):
        """Récupère les détails d'une zone (incluant les records)."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/servers/{self.server_id}/zones/{zone_id}",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()

    async def create_zone(self, domain: str, kind: str = "Native", nameservers: list = None):
        """Crée une nouvelle zone DNS."""
        if nameservers is None:
            nameservers = [f"ns1.{domain}", f"ns2.{domain}"]
            
        payload = {
            "name": domain if domain.endswith('.') else f"{domain}.",
            "kind": kind,
            "masters": [],
            "nameservers": nameservers
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/servers/{self.server_id}/zones",
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()
            return response.json()

    async def delete_zone(self, zone_id: str):
        """Supprime une zone."""
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{self.base_url}/servers/{self.server_id}/zones/{zone_id}",
                headers=self.headers
            )
            if response.status_code != 204:
                response.raise_for_status()
            return True

    async def manage_record(self, zone_id: str, name: str, rtype: str, content: list, ttl: int = 3600, changetype: str = "REPLACE"):
        """Ajoute, modifie ou supprime des records (RRsets)."""
        # content est une liste de valeurs. Pour supprimer, passer une liste vide et changetype="DELETE"
        
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
        
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{self.base_url}/servers/{self.server_id}/zones/{zone_id}",
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()

    async def batch_apply_records(self, zone_id: str, rrsets: list):
        """Applique plusieurs modifications de records en une seule requête."""
        payload = {"rrsets": rrsets}
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{self.base_url}/servers/{self.server_id}/zones/{zone_id}",
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()
