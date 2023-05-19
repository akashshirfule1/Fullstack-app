import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const Register = () => {
  const naviagte=useNavigate();
    const initalValue = {
        name: "",
        email: "",
        password: "",
      };
    const [formvalues, setValue] = useState(initalValue);
    const [formError, setFormError] = useState({});
    const [error, setError] = useState(false);
    const [errorMessage,setErrorMessage] = useState();
  const changeHandler = (e) => {
    const { name, value } = e.target;
    setValue({ ...formvalues, [name]: value });
    setFormError({ ...formError, [name]: "" });
  };


  const Registeruser = (event) => {
    event.preventDefault();
    let validated = validateDetails(formvalues);

    if (Object.keys(validated).length === 0) {
      const data = {
        name: formvalues.name,
        email: formvalues.email,
        password: formvalues.password,
      };
      axios
      .post("http://localhost:3009/api/register", data)
      .then((res) => {
        if(res.data.status==="ok"){
            alert('Accoount Created Successfully')
            naviagte('/login')
        }
        else{
          setError(true);
          setErrorMessage(res.data.error)
        }
      }).catch((err)=>console.log(err))
      
   
    } else {
      setError(true)
      setFormError(validateDetails(formvalues));
    }

  };

  const validateDetails = values => {
    let errors = {};

    if (!values.name) {
      errors.name = "Please enter name";
    } 

    if (!values.password) {
      errors.password = "Please enter password";
    } 

    if (!values.email) {
      errors.email = "Please enter your email";
    }
    return errors;
  };

 
 return (
    <>
     <div className="row mt-5">
        <div className="col-md-4"></div>
        <div className="col-md-4 mt-5 border border-rounded p-3 bg-dark text-white rounded mx-5 registerdiv">
          <h1 className="text-center">Register</h1>
          <form onSubmit={Registeruser}>
          <label htmlFor="name">Name</label>
          <input
            type="text"
            name="name"
            className="form-control"
            value={formvalues.name}
            onChange={changeHandler}
            placeholder="Enter Username"
          />
          {error && <p className="text-danger">{formError.name}</p>}
          <label htmlFor="email" className="mt-2">Email</label>
          <input
            type="email"
            name="email"
            className="form-control"
            value={formvalues.email}
            onChange={changeHandler}
            placeholder="Enter Email"
          />    {error && <p className="text-danger">{formError.email}</p>}
          <label htmlFor="password" className="mt-2">
            Password
          </label>
          <input
            type="password"
            name="password"
            className="form-control"
            value={formvalues.password}
            onChange={changeHandler}
            placeholder="Enter Password"
            autoComplete="on"
          />
              {error && <p className="text-danger">{formError.password}</p>}
              {error && <p className="text-danger">{errorMessage}</p>}
          <button
            type="submit"
            className="btn btn-success mt-3 float-right"
          >
            Submit
          </button>
          <button
            type="button"
            className="btn btn-success mt-3 float-left"
            onClick={()=>naviagte(-1)}
          >
              Back
          </button>
          </form>
        </div>
        <div className="col-md-4"></div>
      </div>
    </>
  )
}

export default Register
