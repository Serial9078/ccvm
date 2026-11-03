import type { NetworkDetail } from "./api";

export function serviceCoverage(scan: NetworkDetail) {
  const audit = scan.jobs.find((job) => job.plugin === "networkaudit");
  const terminal = audit && ["finished", "failed", "cancelled", "skipped"].includes(audit.status);
  const groups = new Map<
    string,
    {
      label: string;
      total: number;
      completed: number;
      shared: number;
      unavailable: number;
      noRule: number;
      pending: number;
      notRun: number;
    }
  >();
  for (const host of scan.observations)
    for (const service of host.services) {
      if (service.state !== "open") continue;
      const label = `${service.port}/tcp · ${service.tunnel ? `${service.tunnel}/` : ""}${service.service || "unknown"}`;
      const group = groups.get(label) || {
        label,
        total: 0,
        completed: 0,
        shared: 0,
        unavailable: 0,
        noRule: 0,
        pending: 0,
        notRun: 0,
      };
      group.total++;
      if (service.audit_coverage === "no_rule") group.noRule++;
      else if (service.audit_coverage === "not_run") group.notRun++;
      else if (service.audit_coverage === "pending") group.pending++;
      else if (!service.checks.length) {
        if (terminal) group.unavailable++;
        else group.pending++;
      } else if (
        service.checks.some((check) => !["completed", "host-level"].includes(check.status))
      )
        group.unavailable++;
      else if (service.checks.some((check) => check.status === "host-level")) group.shared++;
      else group.completed++;
      groups.set(label, group);
    }
  return [...groups.values()].sort((a, b) =>
    a.label.localeCompare(b.label, undefined, { numeric: true }),
  );
}
