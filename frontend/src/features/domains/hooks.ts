import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import {
  getDomains,
  startDiscovery,
} from "./api";

export function useDomains() {
  return useQuery({
    queryKey: ["domains"],
    queryFn: getDomains,
    refetchInterval: 10000,
  });
}

export function useStartDiscovery() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: startDiscovery,
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["dashboard"],
      });

      await queryClient.invalidateQueries({
        queryKey: ["jobs"],
      });

      await queryClient.invalidateQueries({
        queryKey: ["subdomains"],
      });

      await queryClient.invalidateQueries({
        queryKey: ["hosts"],
      });

      await queryClient.invalidateQueries({
        queryKey: ["ports"],
      });

      await queryClient.invalidateQueries({
        queryKey: ["technologies"],
      });
    },
  });
}
