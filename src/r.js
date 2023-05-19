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

  const getAccessTokenExpiration = () => {
    const accessToken = localStorage.getItem("atoken");
    const decodedToken = jwtDecode(accessToken);

    if (decodedToken && decodedToken.exp) {
      // Convert the expiration time from seconds to milliseconds
      const expirationTime = decodedToken.exp * 1000;
	  console.log(decodedToken.exp,decodedToken.exp*1000)
      return expirationTime;
    }
    return null;
  };

  const checkTokenExpiration = () => {
    const accessTokenExpiration = getAccessTokenExpiration();
    const remainingTime = accessTokenExpiration - Date.now();
	// Refresh the token when remaining time is less than 5 minutes (300000 milliseconds)
    if (remainingTime < 300000) {
      refreshToken();
    }
  };

//   const refreshToken = async () => {
//     try {
//       const response = await axios.post(
//         "http://localhost:3009/api/refresh-token",
//         {
//           refreshToken: rtoken,
//         }
//       );

//       const data = response.data;

//       if (data.status === "ok") {
//         const newAccessToken = data.atoken;
//         localStorage.setItem("atoken", newAccessToken);
//       } else {
//         console.error(data.error);
//       }
//     } catch (error) {
//       console.error(error);
//     }
//   };


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
  


  useEffect(() => {
    const token = localStorage.getItem("atoken");
    if (token) {
      const user = jwt(token);
      if (user) {
        setLoginuser(user.email);
        populateQuote();
      } else {
        localStorage.removeItem("atoken");
        window.location.href = "/";
      }
    }
    checkTokenExpiration();
    setInterval(checkTokenExpiration, 60000);
  }, []);

//   async function populateQuote() {
//     try {
//       const response = await axios.get("http://localhost:3009/api/quote", {
//         headers: {
//           "x-access-token": localStorage.getItem("atoken"),
//         },
//       });

//       if (response.data.status === "ok") {
//         setQuote(response.data.quote);
//       } else {
//         window.location.href = "/";
//         localStorage.removeItem("atoken");
//       }
//     } catch (error) {
//       console.error("An error occurred while calling the API:", error);
//     }
//   }

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
		  window.location.href = "/";
		  localStorage.removeItem("atoken");
		}
	  })
	  .catch((error) => {
		console.error("An error occurred while calling the API:", error);
	  });
  };
  
  const rtoken = localStorage.getItem("rtoken");
  useEffect(() => {
    const token = localStorage.getItem("atoken");

    if (token) {
      const user = jwt(token);
      console.log(token);
      if (user) {
        console.log(user);
        setLoginuser(user.email);
        populateQuote();
      } else {
        localStorage.removeItem("atoken");
        window.location.href = "/";
      }
    }
  }, []);

//   async function updateQuote(event) {
//     event.preventDefault();

//     try {
//       const response = await axios.post(
//         "http://localhost:3009/api/quote",
//         {
//           quote: tempQuote,
//         },
//         {
//           headers: {
//             "Content-Type": "application/json",
//             "x-access-token": localStorage.getItem("atoken"),
//           },
//         }
//       );

//       if (response.data.status === "ok") {
//         setQuote(tempQuote);
//         setTempQuote("");
//       } else {
//         alert("Please login again");
//         localStorage.removeItem("atoken");
//         window.location.href = "/";
//       }
//     } catch (error) {
//       console.error("An error occurred while calling the API:", error);
//     }
//   }

const updateQuote = (event) => {
	event.preventDefault();
  
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
		console.error("An error occurred while calling the API:", error);
	  });
  };
  
  const Logout = () => {
    localStorage.removeItem("atoken");
    localStorage.removeItem("rtoken");
    navigate("/");
  };

  const token = localStorage.getItem("atoken");
  return (
    <div>
      {token ? (
        <div className="row mt-5 mx-3">
          <div className="col-md-4"></div>
          <div className="col-md-4 mt-5 pt-5 bg-success">
            <h1>Hello {loginuser}</h1>
            {quote && <h2>--- {quote}</h2>}
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
                value="Update quote"
                className="mt-3 mb-3 btn btn-secondary m-1 float-right p-2"
              />
            </form>
          </div>
          <div className="col-md-4">
            <button className="float-left mt-5 btn btn-danger" onClick={Logout}>
              Logout
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
