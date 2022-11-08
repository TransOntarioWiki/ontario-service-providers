import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import Services from "./Services";
import Privacy from "./Privacy";
import EditProvider from "./EditProvider";
import ProviderOverlay from "./ProviderOverlay";
import Tos from "./Tos";
import NotFound from "./NotFound";
import reportWebVitals from "./reportWebVitals";
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import { QueryClientProvider } from "react-query";
import { queryClient } from "./api";
import OAuth from "./OAuth";
import "./index.css";

const root = ReactDOM.createRoot(document.getElementById("root"));

const router = createBrowserRouter([
  {
    path: "/",
    element: <Services />,
  },
  {
    path: "/provider/:providerSlug",
    element: <ProviderOverlay />,
  },
  {
    path: "/provider/:providerSlug/edit",
    element: <EditProvider />,
  },
  {
    path: "/create-provider",
    element: <EditProvider />,
  },
  {
    path: "/oauth",
    element: <OAuth />,
  },
  {
    path: "/privacy",
    element: <Privacy />,
  },
  {
    path: "/tos",
    element: <Tos />,
  },
  {
    path: "*",
    element: <NotFound />,
  },
]);

root.render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
