import { ReactSearchAutocomplete } from "react-search-autocomplete";
import { useSearchParams } from "react-router-dom";

import regions from "./regions";
import { useServices } from "./api";
import PillButtonInput from "./PillButtonInput";

function paramsToObject(entries) {
  const result = {};
  for (const [key, value] of entries) {
    // each 'entry' is a [key, value] tupple
    result[key] = value;
  }
  return result;
}

const SearchForm = () => {
  const servicesData = useServices();
  const services = servicesData.data;
  const [searchParams, setSearchParams] = useSearchParams();

  return (
    <form>
      <div
        className="flex flex-wrap justify-center gap-2 mb-4"
        onChange={(ev) => {
          setSearchParams({
            ...paramsToObject(searchParams),
            region: ev.target.value,
          });
        }}
      >
        {Object.entries(regions).map(([api, ux]) => (
          <PillButtonInput
            key={api}
            name="region"
            value={api === "null" ? "is.null" : `eq.${api}`}
            label={ux}
            currentValue={searchParams.get("region")}
          />
        ))}
      </div>
      <div className="flex flex-col items-center">
        <label htmlFor="services" className="w-fit mr-4">
          Filter by Service
        </label>
        <div className="w-full">
          {services ? (
            <ReactSearchAutocomplete
              items={services}
              onSelect={(item) => {
                setSearchParams({
                  ...paramsToObject(searchParams),
                  services: `cs.{${item.name}}`,
                });
              }}
              onClear={() => {
                const obj = paramsToObject(searchParams);
                delete obj.services;
                setSearchParams(obj);
              }}
              autoFocus={false}
            />
          ) : null}
        </div>
      </div>
    </form>
  );
};

export default SearchForm;
