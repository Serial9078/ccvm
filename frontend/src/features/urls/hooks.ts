import { useQuery } from "@tanstack/react-query";

import { getUrlInventory } from "./api";

export function useUrls() {
  return useQuery({
    queryKey: ["urls", "inventory"],
    queryFn: getUrlInventory,
    refetchInterval: 10000,
  });
}
