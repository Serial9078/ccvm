from collections.abc import Callable

from sqlalchemy.orm import Session

from app.models.job import Job
from app.plugins.katana import run_katana
from app.plugins.legacy import (
    run_dnsx,
    run_dummy,
    run_httpx,
    run_naabu,
    run_nuclei,
    run_subfinder,
)

PluginHandler = Callable[
    [Session, Job],
    None,
]


PLUGIN_REGISTRY: dict[
    str,
    PluginHandler,
] = {
    "subfinder": run_subfinder,
    "dnsx": run_dnsx,
    "httpx": run_httpx,
    "naabu": run_naabu,
    "katana": run_katana,
    "nuclei": run_nuclei,
    "dummy": run_dummy,
}


def get_plugin(
    name: str,
) -> PluginHandler | None:
    return PLUGIN_REGISTRY.get(
        name.strip().lower()
    )


def list_plugins() -> list[str]:
    return sorted(
        PLUGIN_REGISTRY.keys()
    )
