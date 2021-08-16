import { h }                    from "preact";
import { faHeart }              from "@fortawesome/free-solid-svg-icons";
import { faCopyright }          from "@fortawesome/free-regular-svg-icons";
import { faGithub, faTwitter }  from "@fortawesome/free-brands-svg-icons"
import { library as fa_lib }    from "@fortawesome/fontawesome-svg-core";
fa_lib.add( faHeart, faGithub, faTwitter );

import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

export default function Footer()
{
    return(
        <footer class="my-md-3 pt-md-3 border-top">
            <div class="d-flex">
                <div class="me-auto">
                    <span>
                        Made with<FontAwesomeIcon icon={faHeart} color="Red" className="mx-2"/>by <b>Angelfor3v3r</b>.
                    </span>
                </div>
                <div class="ms-auto text-muted">
                    <FontAwesomeIcon icon={faCopyright} className="mx-1"/>2021
                </div>
            </div>
            <div class="d-flex">
                <div class="me-auto">
                    <span>
                        Find me on:
                        <a href="https://github.com/angelfor3v3r"><FontAwesomeIcon icon={faGithub} size="lg" className="mx-1"/></a>
                        <a href="https://twitter.com/xx63564463"><FontAwesomeIcon icon={faTwitter} size="lg" className="mx-1"/></a>
                    </span>
                </div>
            </div>
        </footer>
    );
}