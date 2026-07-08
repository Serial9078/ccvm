import { useQuery } from "@tanstack/react-query";
import { getPorts } from "./api";

export function usePorts() {
  return useQuery({
    queryKey: ["ports"],
    queryFn: getPorts,
    refetchInterval: 5000,
  });
}
