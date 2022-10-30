import { useEffect } from "react";
import { useForm, Form, Field } from "react-final-form";
import { ReactSearchAutocomplete } from "react-search-autocomplete";
import { useQuery } from "react-query";

import regions from "./regions";
import { fetchServices } from "./api";
import PillButtonInput from "./PillButtonInput";

const autoCompleteWrapper = ({ input, items }) => (
  <ReactSearchAutocomplete
    items={items}
    onSelect={item => input.onChange(item.name)}
    onSearch={search => input.onChange(search)}
  />
);

const Listener = ({ values }) => {
  const { submit } = useForm();

  useEffect(() => {
    submit(values);
  }, [submit, values])

  return null;
};

const SearchForm = ({ onSearch }) => {
  const { data: services } = useQuery(["services"], fetchServices);

  return (
    <Form onSubmit={onSearch}>
      {({ handleSubmit, values }) => (
        <form onSubmit={handleSubmit}>
          <Listener values={values} />
          <div className="flex flex-wrap justify-center gap-2 mb-4">
            {Object.entries(regions).map(([api, ux]) => (
              <PillButtonInput name="region" value={api} label={ux} />
            ))}
          </div>
          <div className="flex flex-col items-center">
            <label htmlFor="service" className="w-fit mr-4">Filter by Service</label>
            <div className="w-full">
            <Field type="text" component={autoCompleteWrapper} name="service" items={services} />
            </div>
          </div>
        </form>
      )}
    </Form>
  );
};

export default SearchForm;
