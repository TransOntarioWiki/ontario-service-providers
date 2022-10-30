import { useState, useEffect } from "react";
import axios from "axios";
import { useForm, Form, Field } from "react-final-form";
import { ReactSearchAutocomplete } from "react-search-autocomplete";

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
  }, [values])

  return null;
};

const SearchForm = ({ onSearch }) => {
  const [services, setServices] = useState([{ id: 1, name: "electrolysis"}]);

  useEffect(() => {
    axios.get("/services/").then(response => {
      setServices(response.data);
    }).catch(() => {});
  }, []);

  return (
    <Form onSubmit={onSearch}>
      {({ handleSubmit, values }) => (
        <form onSubmit={handleSubmit}>
          <Listener values={values} />
          <div className="flex flex-wrap justify-center gap-2 mb-4">
            <PillButtonInput name="region" value="durham" label="GTA - Durham Region" />
            <PillButtonInput name="region" value="york" label="GTA - York Region" />
            <PillButtonInput name="region" value="toronto" label="GTA - Peel Region" />
            <PillButtonInput name="region" value="ottawa" label="Ottawa and Eastern Ontario" />
            <PillButtonInput name="region" value="hamilton" label="Hamilton-Burlington-Oakville" />
            <PillButtonInput name="region" value="kw" label="Kitchener-Cambridge-Waterloo" />
            <PillButtonInput name="region" value="london" label="London" />
            <PillButtonInput name="region" value="niagara" label="St Catharines-Niagara" />
            <PillButtonInput name="region" value="windsor" label="Windsor" />
            <PillButtonInput name="region" value="barrie" label="Barrie and Central Ontario" />
            <PillButtonInput name="region" value="sudbury" label="Sudbury-North Bay-Sault Ste Marie and Northeast Ontario" />
            <PillButtonInput name="region" value="thunder bay" label="Thunder Bay and Northwest Ontario" />
            <PillButtonInput name="region" value="kingston" label="Belleville-Kingston-Quinte West" />
            <PillButtonInput name="region" value="sarnia" label="Sarnia" />
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
