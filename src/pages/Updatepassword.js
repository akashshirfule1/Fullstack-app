import React , {useState} from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import Login from "./Login";

const Updatepassword = () => {
  const navigate=useNavigate()
    const initalValue1 = {
        email: "",
        password: "",
        newPassword:''
      };
    
      const [formvalues1, setValue1] = useState(initalValue1);
      const [formError, setFormError] = useState({});
      const [errorMessage,setErrorMessage] = useState();
      const [error, setError] = useState(false);
      
      const changeHandler1 = (e) => {
        const { name, value } = e.target;
        setValue1({ ...formvalues1, [name]: value });
      };
    
      const Forgetuserpassword =  (event) => {
        event.preventDefault();
        const validated=validateDetails(formvalues1)

      if((Object.keys(validated).length === 0) ){  
        const data = {
          email: formvalues1.email,
          password: formvalues1.password,
          newPassword:formvalues1.newPassword
        };
         axios
          .post("http://localhost:3009/api/update-password", data)
          .then((res) => {
            if(res.data.message){
                console.log(res);
                alert(res.data.message);
                navigate('/dashboard')
            }
            else{
              setError(true);
              setErrorMessage(res.data.error)
            }
          }
          )
          .catch((err) => {
           console.log(err);
          })
      }
      else{
        setError(true)
        setFormError(validateDetails(formvalues1));
      }
    }

      const validateDetails=(values)=>{
       const errors={};

       if (!values.email) {
        errors.email = "Please enter your email";
      } 
  
      if (!values.password) {
        errors.password = "Please enter your password";
      }

      
      if (!values.newPassword) {
        errors.newPassword = "Please enter your new password";
      }
      else if(values.newPassword===values.password){
        errors.newPassword = "The new password and old password must be different";
      }


      return errors;
      }

      const token =localStorage.getItem('atoken')
  return (
    <>
 {token ? <div className="row mt-5">
        <div className="col-md-4"></div>
        <div className="col-md-4 mt-5 border border-rounded p-3 bg-dark text-white rounded mx-4 logindiv">
        <h1 className="text-center">Update Password</h1>
          <label htmlFor="email">Email</label>
          <input
            type="text"
            name="email"
            className="form-control"
            value={formvalues1.email}
            onChange={changeHandler1}
            placeholder="Enter Email"
          />{error && <p className="text-dark"><b>{formError.email}</b></p>}
          <label htmlFor="password" className="mt-2">
            Password
          </label>
          <input
            type="password"
            name="password"
            className="form-control"
            value={formvalues1.password}
            onChange={changeHandler1}
            placeholder="Enter Password"
          />{error && <p className="text-dark"><b>{formError.password}</b></p>}

          <label htmlFor="email">New Password</label>
          <input
            type="password"
            name="newPassword"
            className="form-control"
            value={formvalues1.newPassword}
            onChange={changeHandler1}
            placeholder="Enter Email"
          />{error && <p className="text-dark"><b>{formError.newPassword}</b></p>}

            {error && <p className="text-dark"><b>{errorMessage}</b></p>}
        <div>  <button
            type="button"
            className="btn btn-success mt-3 float-right"
            onClick={Forgetuserpassword}
          >
            Update
          </button>
{ token ? 
          <button
            type="button"
            className="btn btn-success mt-3 float-left"
            onClick={()=>navigate('/dashboard')}
          >
            Back
          </button> :      <button
            type="button"
            className="btn btn-success mt-3 float-left"
            onClick={()=>navigate('/login')}
          >
            Login
          </button>
           }
          </div>
        </div>
        <div className="col-md-4"></div>
      </div> :<Login></Login>}
    </>
  )
}

export default Updatepassword;
