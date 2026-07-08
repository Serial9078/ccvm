import { useQuery } from "@tanstack/react-query";
import { getTechnologies } from "./api";

export function useTechnologies() {
  return useQuery({
    queryKey: ["technologies"],
    queryFn: getTechnologies,
    refetchInterval: 5000,
  });
}
