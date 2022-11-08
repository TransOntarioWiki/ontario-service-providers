import Select from "react-select";
import { useSearchParams } from "react-router-dom";
import { useMemo } from "react";

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
  const services = useMemo(
    () =>
      servicesData.data?.map((service) => ({
        label: service.name,
        value: `cs.{${service.name}}`,
      })),
    [servicesData.data]
  );
  const [searchParams, setSearchParams] = useSearchParams();

  const selectedService =
    services?.find((opt) => opt.value === searchParams.get("services"))
      ?.label || "";

  return (
    <form>
      <div className="flex flex-wrap justify-center gap-2 mb-4">
        {Object.entries(regions).map(([api, ux]) => (
          <PillButtonInput
            key={api}
            name="region"
            value={api === "null" ? "is.null" : `eq.${api}`}
            label={ux}
            currentValue={searchParams.get("region")}
            onSetCurrentValue={(value) => {
              if (value) {
                setSearchParams({
                  ...paramsToObject(searchParams),
                  region: value,
                });
              } else {
                const params = paramsToObject(searchParams);
                delete params.region;
                setSearchParams(params);
              }
            }}
          />
        ))}
      </div>
      <div className="flex flex-col items-center">
        <label htmlFor="services" className="w-fit mr-4">
          Filter by Service
        </label>
        <div className="w-full">
          {services ? (
            <Select
              options={services}
              isSearchable
              isClearable
              defaultInputValue={selectedService}
              onChange={(option) => {
                if (option) {
                  setSearchParams({
                    ...paramsToObject(searchParams),
                    services: option.value,
                  });
                } else {
                  const obj = paramsToObject(searchParams);
                  delete obj.services;
                  setSearchParams(obj);
                }
              }}
            />
          ) : null}
        </div>
      </div>
    </form>
  );
};

export default SearchForm;
