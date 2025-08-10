import { ReactNode } from "react";
import { Metadata } from "next";

export const metadata: Metadata = {
  title: "OIDC Authentication - God Mode",
};

export default function OIDCAuthenticationLayout({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
