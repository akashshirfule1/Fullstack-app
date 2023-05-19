import React from "react";
import {BrowserRouter as Router,Route, Routes} from 'react-router-dom';
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Updatepassword from "./pages/Updatepassword";
import Forgotpassword from "./pages/Forgetpassword";
function App() {
  return (
    <div>
    <Router>
      <Routes>
      <Route path="/"  element={<Login/>}/>
      <Route path="/login"  element={<Login/>}/>
      <Route path="/register"  element={<Register/>}/>
      <Route path="/dashboard"  element={<Dashboard/>}/>
      <Route path="/update"  element={<Updatepassword/>}/>
      <Route path="/forget"  element={<Forgotpassword/>}/>
      <Route path="*" element={<h1 className="text-center mt-5">Page not found</h1>}></Route>
      </Routes>
    </Router>
    </div>
  );
}

export default App;
