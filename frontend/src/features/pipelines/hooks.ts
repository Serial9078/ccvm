import { useQuery } from "@tanstack/react-query";

import {
  getPipeline,
  getPipelines,
} from "./api";

export function usePipelines() {
  return useQuery({
    queryKey: ["pipelines"],
    queryFn: getPipelines,
    refetchInterval: 3000,
  });
}

export function usePipeline(
  pipelineId: string,
) {
  return useQuery({
    queryKey: [
      "pipelines",
      pipelineId,
    ],
    queryFn: () => getPipeline(
      pipelineId,
    ),
    enabled: Boolean(pipelineId),
    refetchInterval: 3000,
  });
}
