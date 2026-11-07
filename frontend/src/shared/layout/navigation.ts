export const navigationGroups = [
  {
    label: "Web",
    items: [
      { label: "Domains", path: "/domains", icon: "domain" },
      { label: "URLs", path: "/urls", icon: "link" },
    ],
  },
  {
    label: "Infrastruktur",
    items: [
      { label: "Netzwerk", path: "/networks", icon: "network" },
      { label: "Windows Server", path: "/windows-servers", icon: "server" },
      { label: "Windows Clients", path: "/windows-clients", icon: "client" },
      { label: "Linux", path: "/linux", icon: "terminal" },
      { label: "VMware", path: "/vmware", icon: "virtualization" },
    ],
  },
  {
    label: "Betrieb",
    items: [
      { label: "Scans", path: "/scans", icon: "radar" },
      { label: "Findings", path: "/findings", icon: "finding" },
      { label: "Pipelines", path: "/pipelines", icon: "pipeline" },
      { label: "Berichte", path: "/reports", icon: "report" },
    ],
  },
  {
    label: "Details",
    items: [
      { label: "Host-Inventur", path: "/host-audits", icon: "inventory" },
      { label: "Subdomains", path: "/subdomains", icon: "public" },
      { label: "Hosts", path: "/hosts", icon: "server" },
      { label: "Ports", path: "/ports", icon: "network" },
      { label: "Technologien", path: "/technologies", icon: "technology" },
      { label: "Screenshots", path: "/screenshots", icon: "image" },
      { label: "Assets", path: "/assets", icon: "devices" },
      { label: "Einstellungen", path: "/settings", icon: "settings" },
    ],
  },
] as const;

/** Customer context is safe in a URL; tokens and other query data are not copied. */
export function customerNavigationSearch(search: string): string {
  const values = new URLSearchParams(search).getAll("customer_id");
  if (values.length !== 1 || !/^[1-9]\d{0,9}$/.test(values[0])) return "";
  return `?customer_id=${values[0]}`;
}
