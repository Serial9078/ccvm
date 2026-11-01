import { useQuery } from "@tanstack/react-query";

import { getScreenshotInventory } from "./api";

export function useScreenshotInventory() {
  return useQuery({
    queryKey: [
      "screenshots",
      "inventory",
    ],
    queryFn: getScreenshotInventory,
    refetchInterval: 15000,
  });
}
