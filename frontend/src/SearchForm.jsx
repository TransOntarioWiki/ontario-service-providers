import { useState, useEffect } from "react";
import axios from "axios";
import { useForm, Form, Field } from "react-final-form";
import { ReactSearchAutocomplete } from "react-search-autocomplete";

import regions from "./regions";
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
  const [services, setServices] = useState([]);

  useEffect(() => {
    axios.get("/service").then(response => {
      setServices(response.data.map(x => ({ id: x.service, name: x.service })));
    }).catch(() => {});
  }, []);

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
            <label for="service" className="w-fit mr-4">Filter by Service</label>
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
