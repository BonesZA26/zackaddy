"use strict";

/* ==========================================================
   ZACK ADDY
   MAIN JAVASCRIPT

   Principle:
   JavaScript supports the interface.
   It does not decorate it unnecessarily.
   ========================================================== */


/* ==========================================================
   01. MOBILE NAVIGATION
   ========================================================== */

const menuToggle = document.querySelector(".menu-toggle");
const navigation = document.querySelector(".main-navigation");

if (menuToggle && navigation) {

    const openMenu = () => {
        navigation.classList.add("is-open");

        menuToggle.setAttribute(
            "aria-expanded",
            "true"
        );
    };


    const closeMenu = () => {
        navigation.classList.remove("is-open");

        menuToggle.setAttribute(
            "aria-expanded",
            "false"
        );
    };


    const toggleMenu = () => {

        const isOpen =
            menuToggle.getAttribute("aria-expanded") === "true";

        if (isOpen) {
            closeMenu();
        } else {
            openMenu();
        }
    };


    menuToggle.addEventListener(
        "click",
        toggleMenu
    );


    /* ------------------------------------------------------
       Close navigation after selecting a link
       ------------------------------------------------------ */

    navigation
        .querySelectorAll("a")
        .forEach((link) => {

            link.addEventListener(
                "click",
                closeMenu
            );

        });


    /* ------------------------------------------------------
       Escape closes mobile navigation
       ------------------------------------------------------ */

    document.addEventListener(
        "keydown",
        (event) => {

            if (event.key !== "Escape") {
                return;
            }

            const isOpen =
                menuToggle.getAttribute("aria-expanded") === "true";

            if (!isOpen) {
                return;
            }

            closeMenu();

            menuToggle.focus();
        }
    );


    /* ------------------------------------------------------
       Reset menu if viewport changes back to desktop
       ------------------------------------------------------ */

    const desktopBreakpoint =
        window.matchMedia("(min-width: 801px)");

    const handleBreakpointChange = (event) => {

        if (event.matches) {
            closeMenu();
        }
    };


    if (desktopBreakpoint.addEventListener) {

        desktopBreakpoint.addEventListener(
            "change",
            handleBreakpointChange
        );

    } else {

        /*
           Fallback for older browsers.
        */

        desktopBreakpoint.addListener(
            handleBreakpointChange
        );
    }
}


/* ==========================================================
   02. ACTIVE NAVIGATION SECTION
   ========================================================== */

const observedSections =
    document.querySelectorAll(
        "main section[id]:not(#top)"
    );

const navigationLinks =
    document.querySelectorAll(
        ".main-navigation a[href^='#']"
    );


const clearCurrentNavigation = () => {

    navigationLinks.forEach((link) => {

        link.removeAttribute(
            "aria-current"
        );

    });
};


const setCurrentNavigation = (sectionID) => {

    clearCurrentNavigation();

    const matchingLink =
        document.querySelector(
            `.main-navigation a[href="#${sectionID}"]`
        );

    if (!matchingLink) {
        return;
    }

    matchingLink.setAttribute(
        "aria-current",
        "true"
    );
};


if (
    "IntersectionObserver" in window &&
    observedSections.length > 0
) {

    const sectionObserver =
        new IntersectionObserver(

            (entries) => {

                const visibleEntries =
                    entries
                        .filter(
                            (entry) =>
                                entry.isIntersecting
                        )
                        .sort(
                            (a, b) =>
                                b.intersectionRatio -
                                a.intersectionRatio
                        );


                if (visibleEntries.length === 0) {
                    return;
                }


                const currentSection =
                    visibleEntries[0].target;


                setCurrentNavigation(
                    currentSection.id
                );
            },

            {
                root: null,

                /*
                   Marks a section as current when it occupies
                   the central portion of the viewport.
                */

                rootMargin:
                    "-30% 0px -55% 0px",

                threshold: [
                    0,
                    0.1,
                    0.25,
                    0.5
                ]
            }

        );


    observedSections.forEach(
        (section) => {

            sectionObserver.observe(
                section
            );

        }
    );
}


/* ==========================================================
   03. SMOOTH INTERNAL NAVIGATION
   ========================================================== */

/*
   CSS handles normal smooth scrolling.

   JavaScript only steps in so keyboard focus can follow
   navigation when appropriate.

   Reduced-motion preferences remain respected.
*/

const internalLinks =
    document.querySelectorAll(
        'a[href^="#"]:not([href="#"])'
    );


internalLinks.forEach((link) => {

    link.addEventListener(
        "click",
        (event) => {

            const targetID =
                link.getAttribute("href");

            if (!targetID) {
                return;
            }


            let target;

            try {

                target =
                    document.querySelector(
                        targetID
                    );

            } catch {

                return;
            }


            if (!target) {
                return;
            }


            /*
               Allow normal anchor navigation.

               CSS scroll-behavior controls the motion and
               automatically switches off under
               prefers-reduced-motion.
            */

            if (
                target.id !== "top" &&
                target.id
            ) {

                setCurrentNavigation(
                    target.id
                );
            }

        }
    );

});


/* ==========================================================
   04. FOOTER YEAR
   ========================================================== */

const currentYear =
    document.querySelector(
        "#current-year"
    );


if (currentYear) {

    currentYear.textContent =
        new Date().getFullYear();

}


/* ==========================================================
   05. EXTERNAL LINKS
   ========================================================== */

/*
   Security protection for any future link that opens in
   another tab.

   If target="_blank" is later added to Zack's content,
   rel="noopener noreferrer" is automatically applied.
*/

const externalBlankLinks =
    document.querySelectorAll(
        'a[target="_blank"]'
    );


externalBlankLinks.forEach((link) => {

    const existingRel =
        link
            .getAttribute("rel")
            ?.split(/\s+/)
            .filter(Boolean) || [];


    const relValues =
        new Set(existingRel);


    relValues.add("noopener");
    relValues.add("noreferrer");


    link.setAttribute(
        "rel",
        [...relValues].join(" ")
    );

});


/* ==========================================================
   06. KEYBOARD / POINTER AWARENESS
   ========================================================== */

/*
   Adds a small utility class to the document when the user
   is navigating with the keyboard.

   This does NOT replace :focus-visible.
   It simply gives us a hook if we need one later.
*/

const documentRoot =
    document.documentElement;


document.addEventListener(
    "keydown",
    (event) => {

        if (
            event.key === "Tab" ||
            event.key.startsWith("Arrow")
        ) {

            documentRoot.classList.add(
                "using-keyboard"
            );

        }

    }
);


document.addEventListener(
    "pointerdown",
    () => {

        documentRoot.classList.remove(
            "using-keyboard"
        );

    }
);


/* ==========================================================
   07. DOCUMENT READY STATE
   ========================================================== */

/*
   Gives CSS an optional hook once JavaScript has loaded.

   Useful later if we introduce progressive enhancement.
*/

documentRoot.classList.add(
    "js-enabled"
);