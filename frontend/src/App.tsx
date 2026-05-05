import { Route, Routes } from "react-router-dom";
import Layout from "./components/layout/Layout";
import ATC from "./pages/ATC";
import Forecast from "./pages/Forecast";
import GapAnalysis from "./pages/GapAnalysis";
import ModelMetrics from "./pages/ModelMetrics";
import Overview from "./pages/Overview";
import ThreatGraph from "./pages/ThreatGraph";
import TrendGallery from "./pages/TrendGallery";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/forecast" element={<Forecast />} />
        <Route path="/gap" element={<GapAnalysis />} />
        <Route path="/graph" element={<ThreatGraph />} />
        <Route path="/atc" element={<ATC />} />
        <Route path="/gallery" element={<TrendGallery />} />
        <Route path="/metrics" element={<ModelMetrics />} />
      </Routes>
    </Layout>
  );
}
