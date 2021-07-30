import { h } from "preact";
import { Link } from "preact-router/match";

const Header = () => (
    <header>
        <nav class="navbar navbar-dark bg-dark navbar-expand-lg">
            <div class="container-fluid">
                <span class="navbar-brand h1">Eccologic ASM</span>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarCollapse">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarCollapse">
                    <ul class="navbar-nav me-auto mb-2 mb-md-0">
                        <li class="nav-item">
                            <Link className="nav-link" activeClassName="active" href="/">Home</Link>
                        </li>
                        <li class="nav-item">
                            <Link className="nav-link" activeClassName="active" href="/help">Help</Link>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>
    </header>
);

export default Header;