# How to setup the grafana dashboard

The Content Cache charm supports metric collection with COS integration.
The [COS](https://charmhub.io/topics/canonical-observability-stack) or [COS Lite](https://charmhub.io/topics/canonical-observability-stack/editions/lite) instance includes a grafana instance, which can be configured to visualize the metrics collected.

## Importing the grafana dashboard

1. Go to the grafana website of the COS or COS lite, and log in.
2. At the home page after logging in, there should be a three bar icon below the grafana icon. Click on it and click on "Dashboards".
3. There should be a "New" button on the right side of the page. Click on it and select "Import".
4. Load the `grafana-dashboard/content_cache.json` into the website. You can either upload it as a file with "Upload dashboard JSON file" or copy the json file content to "Import via panel json". Once done click "Load".
