import { h }       from "preact";
import { NavLink } from "react-router-dom";

export default function Header()
{
    return(
        <header>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container-fluid">
                    <span class="navbar-brand h1">Eccologic ASM</span>
                    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent">
                        <span class="navbar-toggler-icon"></span>
                    </button>
                    <div class="collapse navbar-collapse" id="navbarCollapse">
                        <ul class="navbar-nav me-auto mb-2 mb-md-0">
                            <li class="nav-item">
                                <NavLink to="/" className="nav-link" aria-current="false" exact>Home</NavLink>
                            </li>
                            <li class="nav-item">
                                <NavLink to="/help" className="nav-link" aria-current="false">Help</NavLink>
                            </li>
                        </ul>
                    </div>
                </div>
            </nav>
        </header>
    );
}