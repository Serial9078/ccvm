import { useQuery } from "@tanstack/react-query";
import { getFindings } from "./api";

export function useFindings() {
  return useQuery({
    queryKey: ["findings"],
    queryFn: getFindings,
    refetchInterval: 5000,
  });
}
