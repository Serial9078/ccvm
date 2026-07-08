import { useQuery } from "@tanstack/react-query";
import { getSubdomains } from "./api";

export function useSubdomains() {
  return useQuery({
    queryKey: ["subdomains"],
    queryFn: getSubdomains,
    refetchInterval: 5000,
  });
}
