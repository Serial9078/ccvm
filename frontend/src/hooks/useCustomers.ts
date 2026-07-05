import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createCustomer, getCustomers } from "../api/customers";
import type { CustomerCreate } from "../api/customers";

export function useCustomers() {
  return useQuery({
    queryKey: ["customers"],
    queryFn: getCustomers,
  });
}

export function useCreateCustomer() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: CustomerCreate) => createCustomer(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["customers"] });
    },
  });
}
