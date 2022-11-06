import { useEffect } from "react";
import { Form, Field } from "react-final-form";
import { ReactSearchAutocomplete } from "react-search-autocomplete";
import { useSearchParams } from "react-router-dom";

import regions from "./regions";
import { useServices } from "./api";
import PillButtonInput from "./PillButtonInput";

const autoCompleteWrapper = ({ input, items }) => (
  <ReactSearchAutocomplete
    items={items}
    onSelect={(item) => input.onChange(`cs.{${item.name}}`)}
    onSearch={(search) => input.onChange(search)}
  />
);

const Listener = ({ values }) => {
  const [, setSearchParams] = useSearchParams();

  useEffect(() => {
    setSearchParams(values);
  }, [setSearchParams, values]);

  return null;
};

const SearchForm = () => {
  const servicesData = useServices();
  const services = servicesData.data;

  return (
    <Form onSubmit={() => {}}>
      {({ handleSubmit, values }) => (
        <form onSubmit={handleSubmit}>
          <Listener values={values} />
          <div className="flex flex-wrap justify-center gap-2 mb-4">
            {Object.entries(regions).map(([api, ux]) => (
              <PillButtonInput
                key={api}
                name="region"
                value={api === "null" ? "is.null" : `eq.${api}`}
                label={ux}
              />
            ))}
          </div>
          <div className="flex flex-col items-center">
            <label htmlFor="services" className="w-fit mr-4">
              Filter by Service
            </label>
            <div className="w-full">
              <Field
                type="text"
                component={autoCompleteWrapper}
                name="services"
                items={services}
              />
            </div>
          </div>
        </form>
      )}
    </Form>
  );
};

export default SearchForm;
