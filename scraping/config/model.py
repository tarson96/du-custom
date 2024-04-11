"""This file contains the pydantic classes for the scraping config JSON file.

We use JSON for the configuring the scraping distribution config to make it easier
for miner's to customize their miners, while still being able to take advantage of 
auto-updates, in future.

The classes here are ~identical to their sibling classes in scraping/scraper.py, except
they contain natively serializable/deseriazable fields. All code should use the classes
in scraping/scraper.py. These classes are only intended to be used for deserializing
the scraping_config JSON file.
"""


from typing import List, Optional

from pydantic import BaseModel, Field, PositiveInt, ValidationError
from common import constants
from common.data import DataLabel, StrictBaseModel
from scraping import coordinator
from scraping.scraper import ScraperId


class LabelScrapingConfig(StrictBaseModel):
    """Describes what labels to scrape."""

    label_choices: Optional[List[str]] = Field(
        description="""The collection of labels to choose from when performing a scrape.
        On a given scrape, 1 label will be chosen at random from this list.
        
        An empty list is treated as a non-existant label. In that case, no filter is applied when scraping data from this source.
        """
    )

    max_age_hint_minutes: int = Field(
        description="""The maximum age of data that this scrape should fetch. A random TimeBucket (currently hour block),
        will be chosen within the time frame (now - max_age_hint_minutes, now), using a probality distribution aligned
        with how validators score data freshness.
        
        Note: not all data sources provide date filters, so this property should be thought of as a hint to the scraper, not a rule.
        """,
        default=60 * 24 * constants.DATA_ENTITY_BUCKET_AGE_LIMIT_DAYS,
    )

    max_data_entities: Optional[PositiveInt] = Field(
        default=None,
        description="The maximum number of items to fetch in a single scrape for this label. If None, the scraper will fetch as many items possible.",
    )

    def to_coordinator_label_scrape_config(self) -> coordinator.LabelScrapingConfig:
        """Returns the internal LabelScrapingConfig representation

        Raises:
            ValidationError: if the conversion fails.
        """
        labels = (
            [DataLabel(value=val) for val in self.label_choices]
            if self.label_choices
            else None
        )
        return coordinator.LabelScrapingConfig(
            label_choices=labels,
            max_age_hint_minutes=self.max_age_hint_minutes,
            max_data_entities=self.max_data_entities,
        )


class ScraperConfig(StrictBaseModel):
    """Configures a specific scraper."""

    scraper_id: ScraperId = Field(description="The scraper being configured.")

    cadence_seconds: PositiveInt = Field(
        description="""Configures how often to scrape from this data source, measured in seconds."""
    )

    labels_to_scrape: List[LabelScrapingConfig] = Field(
        description="""Describes the type of data to scrape from this source.
        
        The scraper will perform one scrape per entry in this list every 'cadence_seconds'.
        """
    )

    number_of_parallel_worker: PositiveInt = Field(
        description="Configures how many parallel workers the scraper will use."
    )

    time_between_hashtag_fetch: PositiveInt = Field(
        description="Configures how often to update the trending hastags for this scraper, measured in minutes."
    )

    def to_coordinator_scraper_config(self) -> coordinator.ScraperConfig:
        """Returns the internal ScraperConfig representation

        Raises:
            ValueError: if the conversion fails.
            ValidationError: if the conversion fails.
        """
        return coordinator.ScraperConfig(
            cadence_seconds=self.cadence_seconds,
            number_of_parallel_worker=self.number_of_parallel_worker,
            time_between_hashtag_fetch=self.time_between_hashtag_fetch,
            labels_to_scrape=[
                label.to_coordinator_label_scrape_config()
                for label in self.labels_to_scrape
            ],
        )


class ScrapingConfig(StrictBaseModel):
    scraper_configs: List[ScraperConfig] = Field(
        description="The list of scrapers (and their scraping config) this miner should scrape from. Only scrapers in this list will be used."
    )

    def to_coordinator_config(self) -> coordinator.CoordinatorConfig:
        """Returns the CoordinatorConfig.

        Raises:
            ValidationError: if the conversion fails
        """
        ids_and_configs = [
            [config.scraper_id, config.to_coordinator_scraper_config()]
            for config in self.scraper_configs
        ]
        return coordinator.CoordinatorConfig(
            scraper_configs={id: config for id, config in ids_and_configs}
        )
