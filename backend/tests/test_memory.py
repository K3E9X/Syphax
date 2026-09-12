"""Cross-engagement memory: what held up before, on this kind of stack.

The whole risk of a memory is compounding its own mistakes, so the tests pin
the two properties that prevent that: only final verdicts are recorded, and a
lesson has to earn the right to steer anything.
"""
from app.memory import (MIN_OBSERVATIONS, MIN_PRECISION, Lesson,
                        normalise_tech, outcome_of, rank_lessons,
                        suggested_classes)


def L(tech, cls, confirmed, refuted=0):
    return Lesson(technology=tech, vuln_class=cls, confirmed=confirmed, refuted=refuted)


# ---- only final verdicts are remembered -------------------------------------
def test_only_confirmed_and_false_positive_are_recorded():
    assert outcome_of("confirmed") == "confirmed"
    assert outcome_of("false_positive") == "refuted"
    # A 'likely' is an opinion; remembering opinions compounds them into
    # confident nonsense over successive runs.
    assert outcome_of("likely") is None
    assert outcome_of("unconfirmed") is None
    assert outcome_of(None) is None
    assert outcome_of("") is None


# ---- the join key --------------------------------------------------------- #
def test_versions_are_dropped_so_lessons_are_not_singletons():
    # Tools report the same stack many ways; a version in the key would make
    # every lesson a one-off.
    for raw in ("WordPress 6.2", "wordpress", "WordPress", "wordpress/6.2.1"):
        assert normalise_tech(raw) == "wordpress"
    assert normalise_tech("Apache/2.4.49") == "apache"
    assert normalise_tech("nginx 1.24.0") == "nginx"


def test_waf_names_stay_distinct():
    # Which WAF it is matters; it is the whole point of the lesson.
    assert normalise_tech("waf:cloudflare") == "waf:cloudflare"
    assert normalise_tech("waf:cloudflare") != normalise_tech("waf:akamai")


def test_empty_fingerprints_do_not_become_a_key():
    assert normalise_tech("") == ""
    assert normalise_tech(None) == ""


# ---- a lesson must earn the right to steer --------------------------------- #
def test_one_observation_is_an_anecdote_not_a_lesson():
    assert not L("wordpress", "sqli", confirmed=1).actionable
    assert L("wordpress", "sqli", confirmed=MIN_OBSERVATIONS).actionable


def test_a_class_that_was_mostly_noise_does_not_steer():
    mostly_wrong = L("wordpress", "xss", confirmed=1, refuted=9)
    assert mostly_wrong.precision < MIN_PRECISION
    assert not mostly_wrong.actionable


def test_all_refuted_is_never_actionable():
    lesson = L("wordpress", "xss", confirmed=0, refuted=8)
    assert lesson.precision == 0.0 and not lesson.actionable


def test_precision_of_nothing_is_zero_not_a_crash():
    assert L("x", "y", confirmed=0, refuted=0).precision == 0.0


# ---- ranking --------------------------------------------------------------- #
def test_only_lessons_matching_this_stack_are_returned():
    lessons = [L("wordpress", "sqli", 5), L("drupal", "rce", 9)]
    assert [l.vuln_class for l in rank_lessons(lessons, ["WordPress 6.2"])] == ["sqli"]
    assert rank_lessons(lessons, ["nginx"]) == []
    assert rank_lessons(lessons, []) == []


def test_most_trustworthy_first():
    lessons = [L("wordpress", "weak", 2, refuted=2),      # precision 0.5
               L("wordpress", "solid", 8),                # precision 1.0
               L("wordpress", "mid", 3, refuted=1)]       # precision 0.75
    assert suggested_classes(lessons, ["wordpress"]) == ["solid", "mid", "weak"]


def test_suggested_classes_deduplicates():
    lessons = [L("wordpress", "sqli", 5), L("apache", "sqli", 4)]
    assert suggested_classes(lessons, ["WordPress", "Apache/2.4"]) == ["sqli"]


def test_lesson_payload_is_explainable():
    pub = L("wordpress", "sqli", 3, refuted=1).to_public()
    assert pub["observations"] == 4 and pub["precision"] == 0.75
    assert pub["actionable"] is True
