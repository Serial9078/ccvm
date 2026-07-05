import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createAsset, getAssets } from "../api/assets";
import type { AssetCreate } from "../api/assets";

export function useAssets() {
  return useQuery({
    queryKey: ["assets"],
    queryFn: getAssets,
  });
}

export function useCreateAsset() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: AssetCreate) => createAsset(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
  });
}
