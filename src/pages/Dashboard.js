import React, { useEffect, useState } from "react";
import jwt from "jwt-decode";
import { useNavigate } from "react-router-dom";
import Login from "./Login";
import axios from "axios";
import jwtDecode from "jwt-decode";

const Dashboard = () => {
  const navigate = useNavigate();
  const [quote, setQuote] = useState("");
  const [tempQuote, setTempQuote] = useState("");
  const [loginuser, setLoginuser] = useState("");

  const accessTokenExpiration = () => {
    const accessToken = localStorage.getItem("atoken");
    const decodedToken = jwtDecode(accessToken);

    if (decodedToken && decodedToken.exp) {
      const expirationTime = decodedToken.exp * 1000;
      return expirationTime;
    }
    return null;
  };

  const checkTokenExpiration = () => {
    const expirationTime = accessTokenExpiration();
    const remainingTime = expirationTime - Date.now();
    if (remainingTime < 300000) {
      refreshToken();
    }
  };

const rtoken = localStorage.getItem("rtoken");

const refreshToken = () => {
	axios
	  .post("http://localhost:3009/api/refresh-token", {
		refreshToken: rtoken,
	  })
	  .then((response) => {
		const data = response.data;

		if (data.status === "ok") {
		  const newAccessToken = data.atoken;
		  localStorage.setItem("atoken", newAccessToken);
		} else {
		  console.error(data.error);
		}
	  })
	  .catch((error) => {
		console.error(error);
	  });
  };

  const populateQuote = () => {
	axios
	  .get("http://localhost:3009/api/quote", {
		headers: {
		  "x-access-token": localStorage.getItem("atoken"),
		},
	  })
	  .then((response) => {
		if (response.data.status === "ok") {
		  setQuote(response.data.quote);
		} else {
		  navigate('/')
		  localStorage.removeItem("atoken");
		}
	  })
	  .catch((error) => {
		console.error("error", error);
	  });
  };

  useEffect(() => {
    const token = localStorage.getItem("atoken");
    if (token) {
      const user = jwt(token);
      if (user) {
        setLoginuser(user.email);
        populateQuote();
      } else {
        localStorage.removeItem("atoken");
		navigate('/')
      }
    }
	else {
		navigate('/')
      }
    checkTokenExpiration();
    setInterval(checkTokenExpiration, 60000);
  },[]);


  
const updateQuote = (event) => {
	event.preventDefault();

	if (tempQuote === "") {
		alert("Plz Enter Quote");
		return;
	  }

	axios
	  .post(
		"http://localhost:3009/api/quote",
		{
		  quote: tempQuote,
		},
		{
		  headers: {
			"Content-Type": "application/json",
			"x-access-token": localStorage.getItem("atoken"),
		  },
		}
	  )
	  .then((response) => {
		if (response.data.status === "ok") {
		  setQuote(tempQuote);
		  setTempQuote("");
		} else {
		  alert("Please login again");
		  localStorage.removeItem("atoken");
		  window.location.href = "/";
		}
	  })
	  .catch((error) => {
		console.error("error :", error);
	  });
  };
  
  const Logout = () => {
    localStorage.removeItem("atoken");
    localStorage.removeItem("rtoken");
    navigate("/");
  };

  const token = localStorage.getItem("atoken");
  return (
    <div className="container">
      {token ? (
        <div className="row mt-5 mx-3 justify-content-end">
          <div className="offset-md-4 col-md-4 mt-5 pt-5 bg-success dashboarddiv">


            <h3 className="tokendiv">Hello {loginuser}</h3>
            {quote && <h3>--- {quote}</h3>}

            <form onSubmit={updateQuote}>
              <input
                type="text"
                placeholder="Enter Quote"
                value={tempQuote}
                onChange={(e) => setTempQuote(e.target.value)}
                className="form-control"
              />
              <input
                type="submit"
                value="Update Quote"
                className="mt-3 mb-3 btn btn-secondary m-1 float-right p-2"
              />
            </form>
          </div>
          <div className="col-md-4">
            <button className="mt-5 btn btn-danger" onClick={Logout}>
              Logout
            </button>
			<br></br>
			<button className=" mt-5 btn btn-danger" onClick={()=>navigate('/update')}>
              Update Password
            </button>
          </div>
        </div>
      ) : (
        <Login></Login>
      )}
    </div>
  );
};

export default Dashboard;
