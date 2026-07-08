import { useQuery } from "@tanstack/react-query";
import { getHosts } from "./api";

export function useHosts() {
  return useQuery({
    queryKey: ["hosts"],
    queryFn: getHosts,
    refetchInterval: 5000,
  });
}
