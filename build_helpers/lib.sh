#!/bin/bash

lib::setup::system_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing System Requirements"
    fi

    echo "No system requirements required"

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::setup::python_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing Python Requirements"
    fi

    echo "Installing dpapi-ng"
    if [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ]; then
        DIST_LINK_PATH="$( echo "${PWD}/dist" | sed -e 's/^\///' -e 's/\//\\/g' -e 's/^./\0:/' )"
    else
        DIST_LINK_PATH="${PWD}/dist"
    fi

    # Getting the version is important so that pip prioritises our local dist
    python -m pip install build
    PACKAGE_VERSION="$( python -c "import build.util; print(build.util.project_wheel_metadata('.').get('Version'))" )"

    python -m pip install dpapi-ng=="${PACKAGE_VERSION}" \
        --find-links "file://${DIST_LINK_PATH}" \
        --verbose

    echo "Installing dev dependencies"
    python -m pip install -r requirements-test.txt

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::sanity::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Sanity Checks"
    fi

    python -m black . --check
    python -m isort . --check-only
    python -m mypy .

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    python -m pytest \
        -v \
        --junitxml junit/test-results.xml \
        --cov dpapi_ng \
        --cov-branch \
        --cov-report xml \
        --cov-report term-missing

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}
