from seclab_phantom.models import CertificateObservation, DomainInfrastructure, DomainVariation
from seclab_phantom.providers import CompositeEnrichmentProvider, CrtShProvider


class EnrichmentService:
    def __init__(
        self, ct_provider: CrtShProvider, enrichment_provider: CompositeEnrichmentProvider
    ) -> None:
        self.ct_provider = ct_provider
        self.enrichment_provider = enrichment_provider

    async def enrich_asset(
        self, variation: DomainVariation
    ) -> tuple[DomainVariation, list[CertificateObservation], DomainInfrastructure]:
        certificates = await self.ct_provider.fetch(variation.domain)
        infrastructure = await self.enrichment_provider.enrich(variation.domain)
        return variation, certificates, infrastructure
