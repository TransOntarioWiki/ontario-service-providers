# transontario.wiki

Listings and reviews for trans services in Ontario. For trans Ontarians, by trans Ontarians.

Deployed to [https://transontario.wiki](https://transontario.wiki).

## Architecture

The frontend is a React app in `./frontend`. It is deployed via Netlify.

The backend is written using [PostgREST](https://postgrest.org/en/stable/) in `./db`. Schema changes need to be manually applied.

`./crawl-rho` contains utilities for crawling metadata from Rainbow Health Ontario's [service provider directory](https://www.rainbowhealthontario.ca/lgbt2sq-health/service-provider-directory/).

## Contributing

Please reach out on the [Trans Ontario discord](https://discord.gg/transontario) if you would like to help.
