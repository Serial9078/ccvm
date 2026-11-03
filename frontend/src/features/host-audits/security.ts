export function secureAuditAccess(
  location: { href: string; protocol: string; origin: string },
  base = "/api/v1",
): boolean {
  const url = new URL(base, location.href);
  return (
    location.protocol === "https:" && url.protocol === "https:" && url.origin === location.origin
  );
}
