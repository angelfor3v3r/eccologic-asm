// Imports.
import { h, Component }                 from "preact";
import { BrowserRouter, Switch, Route } from "react-router-dom";

// Component imports.
import Header   from "./header";
import Home     from "./home";
import About    from "./about";
import Help     from "./help";
import NotFound from "./not-found";
import Footer   from "./footer";

// Primary application.
export default class App extends Component
{
    constructor()
    {
        super();
    }

    componentDidMount()
    {
        document.title = "Eccologic ASM";
    }

    render()
    {
        return(
            <BrowserRouter>
                <Header/>
                <div class="container">
                    <Switch>
                        <Route exact path="/" component={Home} exact/>
                        <Route exact path="/about" component={About}/>
                        <Route exact path="/help" component={Help}/>
                        <Route component={NotFound}/>
                    </Switch>
                    <Footer/>
                </div>
            </BrowserRouter>
        );
    }
}