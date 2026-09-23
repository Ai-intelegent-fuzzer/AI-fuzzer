# AI-Fuzzer Frontend

This frontend is the user-facing security operations layer for the AI-Fuzzer project. It provides a professional dashboard for authorized AI security testing, targeted scan configuration, vulnerability findings, reports, and scan history.

## Purpose

The frontend is designed to represent the project as a serious cybersecurity assessment product for academic demonstration. It is focused on clarity, security-oriented design, and maintainable modular architecture.

## Technology Stack

- React
- Vite
- TypeScript
- React Router
- Recharts
- Lucide React
- Plain CSS with design tokens and modular components

## Prerequisites

- Node.js 18+
- npm 9+

## Installation

```bash
npm install
```

## Development

```bash
npm run dev
```

## Production Build

```bash
npm run build
```

## Folder Structure

```text
src/
├── components/
│   ├── common/
│   └── layout/
├── data/
├── pages/
├── services/
├── types/
├── App.tsx
├── main.tsx
├── App.css
├── index.css
└── vite-env.d.ts
```

## Mock Data Architecture

The current implementation uses synthetic mock data only. The UI communicates through a dedicated service layer that abstracts the backend contract, which allows later replacement with a real FastAPI backend without rewriting the view logic.

## Future FastAPI Integration Approach

When the backend is available, the `src/services` layer can be replaced with a real implementation that calls backend endpoints while preserving the same interface. The present mock implementation intentionally avoids fictional endpoints and is designed as a clean boundary between frontend logic and future API integration.
