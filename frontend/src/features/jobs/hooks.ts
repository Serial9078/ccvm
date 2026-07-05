import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createJob, getJobs } from "./api";
import type { JobCreate } from "./api";

export function useJobs() {
  return useQuery({
    queryKey: ["jobs"],
    queryFn: getJobs,
    refetchInterval: 3000,
  });
}

export function useCreateJob() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: JobCreate) => createJob(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
  });
}
