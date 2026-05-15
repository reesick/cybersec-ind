import axios from "axios";

export const api = axios.create({ baseURL: "/api" });

export interface ForecastPoint {
  month: string;
  node: string;
  pred: number;
  ci_lower: number;
  ci_upper: number;
}

export interface ForecastSummary {
  node: string;
  type: string;
  avg_pred: number;
  avg_ci_width: number;
  max_pred: number;
}

export interface GapRow {
  threat: string;
  pat: string;
  category: string;
  [key: string]: string | number;
}

export interface GraphData {
  nodes: { id: string; type: string }[];
  links: { source: string; target: string }[];
}

export interface AtcRow {
  pat: string;
  phase: string;
  slope: number;
  color: string;
  x: number;
  y: number;
  relevance: string;
}

export interface AblationRow {
  model: string;
  RSE: number;
  RAE: number;
}

export interface ValidationMetrics {
  RSE: number;
  RAE: number;
  RMSE: number;
  R2: number;
}
