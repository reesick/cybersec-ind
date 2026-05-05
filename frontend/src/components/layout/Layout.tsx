import { ReactNode } from "react";
import Sidebar from "./Sidebar";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-[#0f172a]">
      <Sidebar />
      <main className="ml-56 min-h-screen p-6">{children}</main>
    </div>
  );
}
