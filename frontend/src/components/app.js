// Imports.
import { h, Component }                 from "preact";
import { BrowserRouter, Switch, Route } from "react-router-dom";

// Component imports.
import Header   from "./header";
import NotFound from "./not-found"
import Home     from "./home";
import Help     from "./help";

// Primary application.
export default function App()
{
    return(
        <BrowserRouter>
            <Header/>
            <Switch>
                <Route path="/" component={Home} exact/>
                <Route path="/help" component={Help}/>
                <Route component={NotFound}/>
            </Switch>
        </BrowserRouter>
    );
}