from collections.abc import Callable

from sqlalchemy.orm import Session

from app.models.job import Job
from app.plugins.headerfindings import (
    run_headerfindings,
)
from app.plugins.headerprobe import (
    run_headerprobe,
)
from app.plugins.hostinventory import run_hostinventory
from app.plugins.katana import (
    run_katana,
)
from app.plugins.legacy import (
    run_dnsx,
    run_dummy,
    run_httpx,
    run_naabu,
    run_nuclei,
    run_subfinder,
)
from app.plugins.network import run_networkaudit, run_networkdiscovery
from app.plugins.nucleiurl import (
    run_nucleiurl,
)
from app.plugins.screenshot import (
    run_screenshot,
)
from app.plugins.urlprobe import (
    run_urlprobe,
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
    "urlprobe": run_urlprobe,
    "headerprobe": run_headerprobe,
    "headerfindings": run_headerfindings,
    "screenshot": run_screenshot,
    "nucleiurl": run_nucleiurl,
    "nuclei": run_nuclei,
    "networkdiscovery": run_networkdiscovery,
    "networkaudit": run_networkaudit,
    "hostinventory": run_hostinventory,
    "dummy": run_dummy,
}


def get_plugin(
    name: str,
) -> PluginHandler | None:
    return PLUGIN_REGISTRY.get(name.strip().lower())


def list_plugins() -> list[str]:
    return sorted(PLUGIN_REGISTRY.keys())
