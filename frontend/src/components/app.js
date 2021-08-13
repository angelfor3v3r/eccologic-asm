// Imports.
import { h, Component }                 from "preact";
import { BrowserRouter, Switch, Route } from "react-router-dom";

// Component imports.
import Header   from "./header";
import Home     from "./home";
import About    from "./about";
import Help     from "./help";
import NotFound from "./not-found";

// Primary application.
export default function App()
{
    return(
        <BrowserRouter>
            <Header/>
            <Switch>
                <Route path="/" component={Home} exact/>
                <Route path="/about" component={About}/>
                <Route path="/help" component={Help}/>
                <Route component={NotFound}/>
            </Switch>
        </BrowserRouter>
    );
}