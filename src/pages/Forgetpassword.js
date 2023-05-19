import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const Forgotpassword = () => {
    const navigate=useNavigate()
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [message1, setMessage1] = useState("");
  const [token, setToken] = useState("");
  const [rtoken, setResettoken] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    axios
      .post("http://localhost:3009/api/forgot-password", { email: email })
      .then((response) => {
        if (response.data.status === "ok") {
          setToken(response.data.resetToken);
        } else {
          setMessage(response.data.error);
        }
      })
      .catch((error) => {
        console.log(error);
        setMessage("Failed  to reset password ");
      });
  };

  const handleSubmit1 = async (e) => {
    e.preventDefault();

    axios
      .post("http://localhost:3009/api/reset-password", {
        resetToken: rtoken,
        newPassword: password,
      })
      .then((response) => {
        if (response.data.status === "ok") {
          alert("New Password Updated Successfully..");
          navigate('/')
        } else {
          setMessage1(response.data.error);
        }
      })
      .catch((error) => {
        console.log(error);
        setMessage1("Failed  to reset password ");
      });
  };


  

  return (
    <div className="">
      <div className="row mt-5">
        <div className="col-md-4"></div>
        <div className="col-md-4 mt-5 border border-rounded p-3 bg-dark text-white rounded mx-2 registerdiv">
          <h1 className="text-center">Forget Password</h1>
          <label htmlFor="email">Email</label>
          <input
            type="text"
            name="email"
            className="form-control"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter Email"
          />
          {message && (
            <p className="text-danger">
              <b>{message}</b>
            </p>
          )}

          <div>
            <button
              type="button"
              className="btn btn-success  float-right mt-2"
              onClick={handleSubmit}
            >
              Send Token
            </button>
          </div>

           {token && (
            <div className="">
              Use this token for forget password
            <p className="tokendiv"> {token}</p>
            </div>
          )} 

          {token && (
            <div className="mt-1">
              <label htmlFor="resettoken">Reset Code</label>
              <input
                type="text"
                name="resettoken"
                className="form-control"
                value={rtoken}
                onChange={(e) => setResettoken(e.target.value)}
                placeholder="Enter Token"
              />

              <label htmlFor="password">New Password</label>
              <input
                type="text"
                name="password"
                className="form-control"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
              />
                        {message1 && (
            <p className="text-danger">
              <b>{message1}</b>
            </p>
          )}
              <div>
                <button
                  type="button"
                  className="btn btn-success mt-3 float-right"
                  onClick={handleSubmit1}
                >
                  Submit
                </button>
              </div>
            </div>
          )}
        </div>
        <div className="col-md-4"></div>
      </div>
    </div>
  );
};

export default Forgotpassword;
