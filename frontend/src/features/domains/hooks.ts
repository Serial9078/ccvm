import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createDomain, getDomains } from "./api";
import type { DomainCreate } from "./api";

export function useDomains() {
  return useQuery({
    queryKey: ["domains"],
    queryFn: getDomains,
  });
}

export function useCreateDomain() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: DomainCreate) => createDomain(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["domains"] });
    },
  });
}
