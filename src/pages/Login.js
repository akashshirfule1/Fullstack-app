import React , {useState} from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const Login = () => {
  const navigate=useNavigate()
    const initalValue1 = {
        email: "",
        password: "",
      };
    
      const [formvalues1, setValue1] = useState(initalValue1);
      const [formError, setFormError] = useState({});
      const [errorMessage,setErrorMessage] = useState();
      const [error, setError] = useState(false);
      
      const changeHandler1 = (e) => {
        const { name, value } = e.target;
        setValue1({ ...formvalues1, [name]: value });
      };
    
      const Loginuser =  (event) => {
        event.preventDefault();
        const validated=validateDetails(formvalues1)

      if((Object.keys(validated).length === 0) ){  
        const data = {
          email: formvalues1.email,
          password: formvalues1.password,
        };
         axios
          .post("http://localhost:3009/api/login", data)
          .then((res) => {
            if(res.data.atoken){
              localStorage.setItem('atoken',res.data.atoken)
              localStorage.setItem('rtoken',res.data.rtoken)
                alert("login successful");
                navigate('/dashboard');
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
      return errors;
      }
  return (
    <div className="">
     <div className="row mt-5">
        <div className="col-md-4"></div>
        <div className="offset-md-4 col-md-4 mt-5 border border-rounded p-3 text-white rounded mx-4 logindiv">
        <h1 className="text-center">Sign In</h1>
        <form>
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
            autoComplete="off"
          />{error && <p className="text-dark"><b>{formError.password}</b></p>}
            {error && <p className="text-dark"><b>{errorMessage}</b></p>}
        <div><button
            type="button"
            className="btn btn-success mt-3 float-right"
            onClick={Loginuser}
          >
            Login
          </button>
          
          <button
            type="button"
            className="btn btn-success mt-3 mx-5"
            onClick={()=>navigate("/forget")}
          >
            Forget Password
          </button>

          <button
            type="button"
            className="btn btn-success mt-3 float-left"
            onClick={()=>navigate("/register")}
          >
            Register
          </button>
      
          </div>
          </form>
        </div>    
        <div className="col-md-4"></div>
      </div>

      
    </div>
  )
}

export default Login
